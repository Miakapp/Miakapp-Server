package relay

import (
	"errors"
	"fmt"

	protocol "github.com/miakapp/miakapp-v3/protocol/go"
)

const (
	codeMalformedFrame     int64 = 1000
	codeUnsupportedVersion int64 = 1001
	codeUnexpectedFrame    int64 = 1002
	codeFrameTooLarge      int64 = 1003
	codeLimitExceeded      int64 = 1004
	codeInvalidValue       int64 = 1005
	codeUnauthenticated    int64 = 1100
	codeTokenExpired       int64 = 1101
	codeInvalidAudience    int64 = 1102
	codeForbidden          int64 = 1200
	codeNotEnrolled        int64 = 1201
	codeNotDeclared        int64 = 1202
	codeWrongDirection     int64 = 1203
	codeConflict           int64 = 1300
	codeDuplicateRequest   int64 = 1301
	codeOwnershipCollision int64 = 1302
	codeStaleEpoch         int64 = 1303
	codeRevisionMismatch   int64 = 1304
	codeGenerationReplaced int64 = 1305
	codeUnavailable        int64 = 1400
	codeNoCoordinator      int64 = 1401
	codeSlowConsumer       int64 = 1402
	codeDeadlineExceeded   int64 = 1403
	codeOutcomeUnknown     int64 = 1404
	codeCancelled          int64 = 1405
	codeInternal           int64 = 1500
)

const (
	closeProtocol      = 4400
	closeAuth          = 4401
	closeAuthorization = 4403
	closeTimeout       = 4408
	closeConflict      = 4409
	closeLimit         = 4429
	closeInternal      = 4500
	closeUnavailable   = 4503
)

type relayError struct {
	code      int64
	retryable bool
	message   string
	closeCode int
	fatal     bool
}

func (err *relayError) Error() string {
	return err.message
}

func applicationError(code int64, retryable bool, message string, closeCode int) *relayError {
	return &relayError{
		code:      code,
		retryable: retryable,
		message:   message,
		closeCode: closeCode,
	}
}

func fatalError(code int64, retryable bool, message string, closeCode int) *relayError {
	err := applicationError(code, retryable, message, closeCode)
	err.fatal = true
	return err
}

func protocolFailure(err error) *relayError {
	var protocolErr *protocol.ProtocolError
	if !errors.As(err, &protocolErr) {
		return fatalError(codeInternal, true, "internal relay failure", closeInternal)
	}
	switch protocolErr.Kind {
	case protocol.ErrFrameTooLarge:
		return fatalError(codeFrameTooLarge, false, "frame exceeds the negotiated limit", closeLimit)
	case protocol.ErrLimit:
		return fatalError(codeLimitExceeded, false, "frame exceeds a protocol limit", closeLimit)
	case protocol.ErrInvalidValue, protocol.ErrInvalidFrame:
		return fatalError(codeInvalidValue, false, "frame contains an invalid value", closeProtocol)
	case protocol.ErrUnknownOpcode, protocol.ErrMalformed, protocol.ErrNonCanonical:
		return fatalError(codeMalformedFrame, false, "malformed protocol frame", closeProtocol)
	default:
		return fatalError(codeMalformedFrame, false, "malformed protocol frame", closeProtocol)
	}
}

func errorFrame(correlationID int64, sourceOpcode byte, failure *relayError) protocol.Frame {
	return protocol.Frame{
		Opcode: protocol.OpcodeError,
		Payload: []any{
			correlationID,
			int64(sourceOpcode),
			failure.code,
			failure.retryable,
			failure.message,
		},
	}
}

func fatalFrame(sourceOpcode byte, failure *relayError) protocol.Frame {
	return protocol.Frame{
		Opcode: protocol.OpcodeFatal,
		Payload: []any{
			int64(sourceOpcode),
			failure.code,
			failure.retryable,
			failure.message,
		},
	}
}

func callFailureFrame(callID, code int64, retryable bool, message string, details any) protocol.Frame {
	return protocol.Frame{
		Opcode:  protocol.OpcodeCallError,
		Payload: []any{callID, code, retryable, message, details},
	}
}

func integer(value any) int64 {
	result, ok := value.(int64)
	if !ok {
		panic(fmt.Sprintf("validated protocol integer has type %T", value))
	}
	return result
}

func stringValue(value any) string {
	result, ok := value.(string)
	if !ok {
		panic(fmt.Sprintf("validated protocol string has type %T", value))
	}
	return result
}

func arrayValue(value any) []any {
	result, ok := value.([]any)
	if !ok {
		panic(fmt.Sprintf("validated protocol array has type %T", value))
	}
	return result
}

func bytesValue(value any) []byte {
	result, ok := value.([]byte)
	if !ok {
		panic(fmt.Sprintf("validated protocol binary has type %T", value))
	}
	return result
}
