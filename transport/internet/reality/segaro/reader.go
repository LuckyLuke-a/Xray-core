package segaro

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/luckyluke-a/xray-core/common/buf"
	"github.com/luckyluke-a/xray-core/common/errors"
	"github.com/luckyluke-a/xray-core/common/signal"
	"github.com/luckyluke-a/xray-core/proxy"
)

var (
	continueErr = errors.New("Continue receiving...")
)

// SegaroReader is used to read xtls-segaro-vision
type SegaroReader struct {
	buf.Reader
	trafficState *proxy.TrafficState
}

func (w *SegaroReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return w.Reader.ReadMultiBuffer()
}

func NewSegaroReader(reader buf.Reader, state *proxy.TrafficState) *SegaroReader {
	return &SegaroReader{
		Reader:       reader,
		trafficState: state,
	}
}

// SegaroRead filter and read xtls-segaro-vision
func SegaroRead(reader buf.Reader, writer buf.Writer, timer *signal.ActivityTimer, conn net.Conn, trafficState *proxy.TrafficState, fromInbound bool, segaroConfig *SegaroConfig, xsvCanContinue chan bool) error {
	defer func() {
		if xsvCanContinue != nil {
			xsvCanContinue <- false
		}
	}()

	authKey, clientTime, err := getRealityAuthkey(&conn, fromInbound)
	if err != nil {
		return err
	}
	paddingSize, subChunkSize := int(segaroConfig.GetPaddingSize()), int(segaroConfig.GetSubChunkSize())

	minServerRandSize, maxServerRandSize := segaroConfig.GetServerRandPacketSize()
	minServerRandCount, maxServerRandCount := segaroConfig.GetServerRandPacketCount()

	minClientRandSize, maxClientRandSize := segaroConfig.GetClientRandPacketSize()
	minClientRandCount, maxClientRandCount := segaroConfig.GetClientRandPacketCount()

	var minRandSize int
	if fromInbound {
		minRandSize = minClientRandSize
	} else {
		minRandSize = minServerRandSize
	}

	err = func() error {
		var totalLength uint16 = 0
		isFirstPacket, isFirstChunk, sendFakePacket := true, true, true
		recievedFakePacket := false
		canDecrypt := true

		cacheMultiBuffer := buf.MultiBuffer{}

		for {
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				timer.Update()
				for _, b := range buffer {
					if isFirstPacket {
						if isFirstChunk {
							isFirstChunk = false
							totalLength = binary.BigEndian.Uint16(b.BytesTo(2))
							b.Advance(2) // Skip total length
						}

						err := readFullBuffer(b, &cacheMultiBuffer, &totalLength, fromInbound, paddingSize, subChunkSize)
						if err == nil {
							if fromInbound {
								// Server side
								headerContent := binary.BigEndian.Uint16(cacheMultiBuffer[0].BytesTo(2))
								cacheMultiBuffer[0].Advance(int32(headerContent) + 2) // Skip requestHeader
								if err := writer.WriteMultiBuffer(cacheMultiBuffer); err != nil {
									return err
								}
							} else {
								// Client side
								if err := isFakePacketsValid(&cacheMultiBuffer, authKey, clientTime, minServerRandSize); err != nil {
									return err
								}
								// Send cached buffers
								for _, buff := range trafficState.CacheBuffer {
									for _, innerBuff := range buff {
										if _, err := conn.Write(innerBuff.Bytes()); err != nil {
											return err
										}
										innerBuff.Release()
									}
								}
								trafficState.CacheBuffer = nil
							}

							isFirstPacket = false

							// Reset for the next round
							cacheMultiBuffer = buf.MultiBuffer{}
							totalLength = 0

						} else if err != continueErr {
							return err
						}

						// Send fake packets
						if fromInbound && sendFakePacket {
							sendFakePacket = false
							if err := sendMultipleFakePacket(authKey, &conn, nil, clientTime, minServerRandSize, maxServerRandSize, minServerRandCount, maxServerRandCount, true); err != nil {
								return err
							}
							xsvCanContinue <- true
						}
					}

					for b.Len() > 0 {
						if !canDecrypt && len(cacheMultiBuffer) == 0 {
							totalLength = binary.BigEndian.Uint16(b.BytesTo(2))
							b.Advance(2) // Skip total length
						}
						err := readFullBuffer(b, &cacheMultiBuffer, &totalLength, canDecrypt, paddingSize, subChunkSize)
						if err == nil {
							if recievedFakePacket {
								recievedFakePacket = false
								canDecrypt = true
								if err := isFakePacketsValid(&cacheMultiBuffer, authKey, clientTime, minRandSize); err != nil {
									return err
								}

							} else {
								if cacheMultiBuffer[0].Len() > 2 {
									if !(fromInbound && (maxClientRandCount == 0 || maxClientRandSize == 0 || minClientRandCount == 0 || minClientRandSize == 0)) && isHandshakeMessage(cacheMultiBuffer[0].BytesTo(3)) {
										recievedFakePacket = true
										canDecrypt = false
									}
								}
								if err := writer.WriteMultiBuffer(cacheMultiBuffer); err != nil {
									return err
								}
							}
							cacheMultiBuffer = buf.MultiBuffer{}
							totalLength = 0
						} else if err != continueErr {
							return err
						}
					}
				}
			}
			if err != nil {
				return err
			}
		}
	}()

	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}

// readFullBuffer, read buffer from multiple chunks and packets
func readFullBuffer(b *buf.Buffer, cacheMultiBuffer *buf.MultiBuffer, totalLength *uint16, decryptBuff bool, paddingSize, subChunkSize int) error {
	canRead := false
	decodedBuff := buf.New()
	*cacheMultiBuffer = append(*cacheMultiBuffer, decodedBuff)

	if *totalLength != 0 {
		canRead = true
	} else if isHandshakeMessage(b.BytesRange(int32(paddingSize)+4, int32(paddingSize)+7)) {
		*totalLength = binary.BigEndian.Uint16(b.BytesTo(2))
		b.Advance(2) // Skip total length bytes
		canRead = true
	}
	if canRead {
		// Accumulate data until we reach the total length
		remainingLength := int32(*totalLength) - cacheMultiBuffer.Len()
		if remainingLength > 0 {
			toRead := remainingLength
			if b.Len() < toRead {
				toRead = b.Len()
			}

			decodedBuff.Write(b.BytesTo(toRead))
			b.Advance(toRead)

			if cacheMultiBuffer.Len() != int32(*totalLength) {
				// Still not enough data, wait for more
				return continueErr
			}
		}
		// All chunks have been loaded into cacheBuffer, now process them
		loadData := []byte{}
		for _, chunk := range *cacheMultiBuffer {
			loadData = append(loadData, chunk.Bytes()...)
		}
		*cacheMultiBuffer = buf.MultiBuffer{}

		for len(loadData) > 0 {
			if len(loadData) < 2 {
				return errors.New("invalid chunk length, missing data")
			}

			// Read the chunk length
			chunkLength := binary.BigEndian.Uint16(loadData[:2])
			loadData = loadData[2:]

			if len(loadData) < int(chunkLength) {
				return errors.New("incomplete chunk received")
			}

			// Extract the chunk content
			chunkContent := loadData[:chunkLength]
			loadData = loadData[chunkLength:]

			// Add the chunk to cacheMultiBuffer
			newBuff := buf.New()
			newBuff.Write(chunkContent)
			*cacheMultiBuffer = append(*cacheMultiBuffer, newBuff)
		}
		if decryptBuff {
			decodeBuff := SegaroRemovePadding(*cacheMultiBuffer, paddingSize, subChunkSize)
			*cacheMultiBuffer = append(buf.MultiBuffer{}, decodeBuff)
		}

	} else {
		if b.Len() > 0 {
			decodedBuff.Write(b.Bytes())
			b.Advance(b.Len())
		}
	}

	return nil
}
