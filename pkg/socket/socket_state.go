package socket

const (
	// Defines different state the TCP Socket can be in
	LISTEN = iota
	SYN_SENT
	SYN_RECEIVED
	ESTABLISHED
	FIN_WAIT_1
	FIN_WAIT_2
	CLOSE_WAIT
	CLOSING
	LAST_ACK
	TIME_WAIT
	CLOSED
)

// ============= Helper ==============

// Given Socket State in int, return the string representation of it
func ToSocketStateStr(state int) string {
	switch state {
	case LISTEN:
		{
			return "LISTEN"
		}
	case SYN_SENT:
		{
			return "SYN_SENT"
		}
	case SYN_RECEIVED:
		{
			return "SYN_RECEIVED"
		}
	case ESTABLISHED:
		{
			return "ESTABLISHED"
		}
	case FIN_WAIT_1:
		{
			return "FIN_WAIT_1"
		}
	case FIN_WAIT_2:
		{
			return "FIN_WAIT_2"
		}
	case CLOSE_WAIT:
		{
			return "CLOSE_WAIT"
		}
	case CLOSING:
		{
			return "CLOSING"
		}
	case LAST_ACK:
		{
			return "LAST_ACK"
		}
	case TIME_WAIT:
		{
			return "TIME_WAIT"
		}
	case CLOSED:
		{
			return "CLOSED"
		}
	default:
		{
			return ""
		}
	}
}
