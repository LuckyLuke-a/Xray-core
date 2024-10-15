package segaro

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/luckyluke-a/xray-core/common/buf"
	"github.com/luckyluke-a/xray-core/common/errors"
	"github.com/luckyluke-a/xray-core/common/signal"
)

var (
	continueErr = errors.New("Continue receiving...")
)

// SegaroReader is used to read xtls-segaro-vision
type SegaroReader struct {
	buf.Reader
}

func NewSegaroReader(reader buf.Reader) *SegaroReader {
	return &SegaroReader{
		Reader: reader,
	}
}

func (w *SegaroReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return w.Reader.ReadMultiBuffer()
}

// SegaroRead filter and read xtls-segaro-vision
func SegaroRead(reader buf.Reader, writer buf.Writer, timer *signal.ActivityTimer, conn net.Conn, fromInbound bool, segaroConfig *SegaroConfig, xsvCanContinue chan bool) error {
	defer func() {
		xsvCanContinue <- false
	}()

	authKey, clientTime, err := getRealityAuthkey(&conn, fromInbound)
	if err != nil {
		return err
	}
	paddingSize, subChunkSize := int(segaroConfig.GetPaddingSize()), int(segaroConfig.GetSubChunkSize())

	minServerRandSize, maxServerRandSize := segaroConfig.GetServerRandPacketSize()
	minServerRandCount, maxServerRandCount := segaroConfig.GetServerRandPacketCount()

	minClientRandSize, _ := segaroConfig.GetClientRandPacketSize()

	var minRandSize int
	if fromInbound {
		minRandSize = minClientRandSize
	} else {
		minRandSize = minServerRandSize
	}

	err = func() error {
		var totalLength uint16
		isFirstPacket, isFirstChunk, sendFakePacket, canDecrypt := true, true, true, true
		receivedFakePacket := false

		var cacheBuffer *buf.Buffer
		cacheMultiBuffer := buf.MultiBuffer{}

		processPacket := func(b *buf.Buffer) error {
			if isFirstChunk {
				isFirstChunk = false
				totalLength = binary.BigEndian.Uint16(b.BytesTo(2))
				b.Advance(2) // Skip total length
				if fromInbound {
					fakePaddingLength := binary.BigEndian.Uint16(b.BytesTo(2)) + 2
					b.Advance(int32(fakePaddingLength)) // Skip fake padding
					totalLength -= fakePaddingLength
				}
			}

			_, err := readFullBuffer(b, &cacheMultiBuffer, &totalLength, fromInbound, paddingSize, subChunkSize)
			return err
		}

		writeOrProcess := func() error {
			if fromInbound {
				headerContent := binary.BigEndian.Uint16(cacheMultiBuffer[0].BytesTo(2))
				cacheMultiBuffer[0].Advance(int32(headerContent) + 2) // Skip requestHeader
				if err := writer.WriteMultiBuffer(cacheMultiBuffer); err != nil {
					return err
				}
			} else {
				if err := isFakePacketsValid(&cacheMultiBuffer, authKey, clientTime, minServerRandSize); err != nil {
					return err
				}
				for _, buff := range segaroConfig.CacheBuffer {
					for _, innerBuff := range buff {
						if _, err := conn.Write(innerBuff.Bytes()); err != nil {
							return err
						}
						innerBuff.Release()
					}
				}
				segaroConfig.CacheBuffer = nil
				xsvCanContinue <- true // ClientSide
			}
			return nil
		}

		for {
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				timer.Update()
				for _, b := range buffer {
					if isFirstPacket {
						if err := processPacket(b); err == nil {
							if err := writeOrProcess(); err != nil {
								return err
							}
							isFirstPacket = false
							cacheMultiBuffer = buf.MultiBuffer{}
							totalLength = 0
						} else if err != continueErr {
							return err
						}
						if fromInbound && sendFakePacket {
							sendFakePacket = false
							if err := sendMultipleFakePacket(authKey, &conn, nil, nil, clientTime, minServerRandSize, maxServerRandSize, minServerRandCount, maxServerRandCount, true); err != nil {
								return err
							}
							xsvCanContinue <- true // ServerSide
						}
					}

					for b.Len() > 0 {
						if !canDecrypt && len(cacheMultiBuffer) == 0 {
							if cacheBuffer != nil {
								totalLength = binary.BigEndian.Uint16([]byte{cacheBuffer.Byte(0), b.Byte(0)})
								b.Advance(1)
								cacheBuffer = nil
							} else if b.Len() < 2 {
								cacheBuffer = buf.New()
								cacheBuffer.Write(b.Bytes())
								b.Advance(b.Len())
								continue
							} else {
								totalLength = binary.BigEndian.Uint16(b.BytesTo(2))
								b.Advance(2) // Skip total length
							}
						}

						shouldProcess, err := readFullBuffer(b, &cacheMultiBuffer, &totalLength, canDecrypt, paddingSize, subChunkSize)
						if err == nil {
							if receivedFakePacket {
								receivedFakePacket = false
								canDecrypt = true
								if err := isFakePacketsValid(&cacheMultiBuffer, authKey, clientTime, minRandSize); err != nil {
									return err
								}
							} else {
								if shouldProcess {
									receivedFakePacket = true
									canDecrypt = false
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
func readFullBuffer(b *buf.Buffer, cacheMultiBuffer *buf.MultiBuffer, totalLength *uint16, decryptBuff bool, paddingSize, subChunkSize int) (shouldProcess bool, err error) {
	decodedBuff := buf.New()
	*cacheMultiBuffer = append(*cacheMultiBuffer, decodedBuff)

	if *totalLength != 0 {
		shouldProcess = true
	} else if b.Len() >= int32(paddingSize)+7 {
		from := int32(paddingSize) + 4
		to := int32(paddingSize) + 7
		if isHandshakeMessage(b.BytesRange(from, to)) || isApplicationDataMessage(b.BytesRange(from, to)) {
			*totalLength = binary.BigEndian.Uint16(b.BytesTo(2))
			b.Advance(2) // Skip total length bytes
			shouldProcess = true
		}
	}
	if shouldProcess {
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
				err = continueErr
				return
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
				err = errors.New("invalid chunk length, missing data")
				return
			}

			// Read the chunk length
			chunkLength := binary.BigEndian.Uint16(loadData[:2])
			loadData = loadData[2:]

			if len(loadData) < int(chunkLength) {
				err = errors.New("incomplete chunk received")
				return
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

	return
}
