package segaro

import (
	"bytes"
	"io"
	"math/rand"
	"net"

	"github.com/luckyluke-a/xray-core/common/buf"
	"github.com/luckyluke-a/xray-core/common/errors"
	"github.com/luckyluke-a/xray-core/common/signal"
)

// SegaroWriter is used to write xtls-segaro-vision
type SegaroWriter struct {
	buf.Writer
	segaroConfig *SegaroConfig
	conn         net.Conn
	initCall     bool
}

func NewSegaroWriter(writer buf.Writer, segaroConfig *SegaroConfig, conn net.Conn) *SegaroWriter {
	return &SegaroWriter{
		Writer:       writer,
		segaroConfig: segaroConfig,
		conn:         conn,
	}
}

func (w *SegaroWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	// The `if` section, only call onetime, at the first packet sent by client and server.
	if !w.initCall {
		w.initCall = true

		minSplitSize, maxSplitSize := w.segaroConfig.GetSplitSize()
		paddingSize := int(w.segaroConfig.GetPaddingSize())
		subChunkSize := int(w.segaroConfig.GetSubChunkSize())
		if maxSplitSize == 0 || paddingSize == 0 || subChunkSize == 0 {
			return errors.New("flow params can not be zero")
		}
		writer, ok := w.Writer.(*buf.BufferedWriter)
		if !ok {
			return errors.New("failed to get buf.BufferedWriter")
		}

		serverSide := false
		var cacheBuffer buf.MultiBuffer

		// Get request header (command, userID and...)
		requestHeader := writer.GetBuffer().Bytes()
		if len(requestHeader) == 2 && bytes.Equal(requestHeader, []byte{0, 0}) {
			serverSide = true
			requestHeader = []byte{}
		}
		// Clear the content
		writer.GetBuffer().Clear()

		if serverSide {
			// Server side
			minServerRandSize, maxServerRandSize := w.segaroConfig.GetServerRandPacketSize()
			minServerRandCount, maxServerRandCount := w.segaroConfig.GetServerRandPacketCount()
			authKey, clientTime, err := getRealityAuthkey(&w.conn, true)
			if err != nil {
				return err
			}
			for _, b := range mb {
				if b.Len() < 3 || !isHandshakeMessage(b.BytesTo(3)) {
					if err := w.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
						return err
					}
					continue
				}

				cacheBuffer = segaroAddPadding(b, minSplitSize, maxSplitSize, paddingSize, subChunkSize)

				// Free the memory
				b.Release()
				b = nil

				// Add meta-data at the first of each chunk
				for _, chunk := range cacheBuffer {
					// Write chunk length
					if _, err := chunk.WriteAtBeginning([]byte{
						byte(chunk.Len() >> 8),
						byte(chunk.Len()),
					}); err != nil {
						return err
					}
				}
				if _, err := cacheBuffer[0].WriteAtBeginning([]byte{
					byte(cacheBuffer.Len() >> 8),
					byte(cacheBuffer.Len()),
				}); err != nil {
					return err
				}
				if err := sendMultipleFakePacket(authKey, nil, &w.Writer, &cacheBuffer, clientTime, minServerRandSize, maxServerRandSize, minServerRandCount, maxServerRandCount, false); err != nil {
					return err
				}
			}
		} else {
			// Client side
			for i, b := range mb {
				if i == 0 || (b.Len() > 2 && isHandshakeMessage(b.BytesTo(3))) {
					newTempBuff := []byte{}
					if i == 0 {
						// Add requestHeader
						newTempBuff = append(newTempBuff, byte(len(requestHeader)>>8), byte(len(requestHeader)))
						newTempBuff = append(newTempBuff, requestHeader...)
					}

					newTempBuff = append(newTempBuff, b.Bytes()...)
					b = buf.FromBytes(newTempBuff)
					newTempBuff = nil

					cacheBuffer = segaroAddPadding(b, minSplitSize, maxSplitSize, paddingSize, subChunkSize)

					// Add meta-data at the first of each chunk
					for _, chunk := range cacheBuffer {
						if _, err := chunk.WriteAtBeginning([]byte{
							byte(chunk.Len() >> 8),
							byte(chunk.Len()),
						},
						); err != nil {
							return err
						}
					}

					if i == 0 {
						firstBuffLen := int(cacheBuffer[0].Len())
						if firstBuffLen < minSplitSize || len(cacheBuffer) == 1 {
							// Use the long padding, to hide the first packet real length
							paddingLength := rand.Intn(maxSplitSize-minSplitSize+1) + minSplitSize
							var paddingBytes []byte
							if paddingLength+firstBuffLen > maxSplitSize {
								if firstBuffLen < paddingLength {
									paddingLength = paddingLength - firstBuffLen
								} else if paddingLength < firstBuffLen {
									paddingLength = firstBuffLen - paddingLength
								} else {
									paddingLength = rand.Intn(100)
								}
								paddingBytes = make([]byte, paddingLength)
							} else {
								paddingBytes = make([]byte, paddingLength)
							}
							generatePadding(paddingBytes)
							if _, err := cacheBuffer[0].WriteAtBeginning(paddingBytes); err != nil {
								return err
							}
							if _, err := cacheBuffer[0].WriteAtBeginning([]byte{
								byte(len(paddingBytes) >> 8),
								byte(len(paddingBytes)),
							}); err != nil {
								return err
							}
							paddingBytes = nil
						} else {
							if _, err := cacheBuffer[0].WriteAtBeginning([]byte{0, 0}); err != nil {
								return err
							}
						}
					}
					if _, err := cacheBuffer[0].WriteAtBeginning([]byte{
						byte(cacheBuffer.Len() >> 8),
						byte(cacheBuffer.Len()),
					}); err != nil {
						return err
					}
				} else {
					cacheBuffer = buf.MultiBuffer{b}
				}

				if i == 0 {
					if err := w.Writer.WriteMultiBuffer(buf.MultiBuffer{cacheBuffer[0]}); err != nil {
						return err
					}
					cacheBuffer = cacheBuffer[1:]
				}

				// Add other chunks to cacheBuffer, if exist
				if len(cacheBuffer) > 0 {
					w.segaroConfig.CacheBuffer = append(w.segaroConfig.CacheBuffer, cacheBuffer)
				}
			}
		}
		cacheBuffer, mb = nil, nil
		return nil
	}
	return w.Writer.WriteMultiBuffer(mb)

}

// SegaroWrite filter and write xtls-segaro-vision
func SegaroWrite(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn net.Conn, fromInbound bool, segaroConfig *SegaroConfig, xsvCanContinue chan bool) error {
	if xsvCanContinue != nil {
		if canContinue := <-xsvCanContinue; !canContinue {
			return errors.New("close conn received from xsv.SegaroRead")
		}
	}
	minSplitSize, maxSplitSize := segaroConfig.GetSplitSize()
	paddingSize, subChunkSize := int(segaroConfig.GetPaddingSize()), int(segaroConfig.GetSubChunkSize())

	var minRandSize, maxRandSize, minRandCount, maxRandCount int
	if fromInbound {
		minRandSize, maxRandSize = segaroConfig.GetServerRandPacketSize()
		minRandCount, maxRandCount = segaroConfig.GetServerRandPacketCount()
	} else {
		minRandSize, maxRandSize = segaroConfig.GetClientRandPacketSize()
		minRandCount, maxRandCount = segaroConfig.GetClientRandPacketCount()
	}
	
	authKey, clientTime, err := getRealityAuthkey(&conn, fromInbound)
	if err != nil {
		return err
	}

	err = func() error {
		for {
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				timer.Update()
				for _, b := range buffer {
					usePadding := false
					if b.Len() > 2 {
						if isHandshakeMessage(b.BytesTo(3)) {
							usePadding = true
						} else if segaroConfig.NumberOfTLSPacketToFilter > 0 && b.Len() < 1000 && isApplicationDataMessage(b.BytesTo(3)) {
							usePadding = true
							segaroConfig.NumberOfTLSPacketToFilter--
						}
					}

					if usePadding {
						newBuff := segaroAddPadding(b, minSplitSize, maxSplitSize, paddingSize, subChunkSize)

						// Add meta-data at the first of each chunk
						for _, chunk := range newBuff {
							if _, err := chunk.WriteAtBeginning([]byte{
								byte(chunk.Len() >> 8),
								byte(chunk.Len()),
							}); err != nil {
								return err
							}
						}
						if _, err := newBuff[0].WriteAtBeginning([]byte{
							byte(newBuff.Len() >> 8),
							byte(newBuff.Len()),
						}); err != nil {
							return err
						}
						if err := sendMultipleFakePacket(authKey, nil, &writer, &newBuff, clientTime, minRandSize, maxRandSize, minRandCount, maxRandCount, false); err != nil {
							return err
						}

					} else {
						if err = writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
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
