package domain

func ValidPrivacyTransition(from, to string) bool {
	switch from {
	case "requested":
		return to == "processing" || to == "rejected" || to == "cancelled"
	case "processing":
		return to == "completed" || to == "rejected" || to == "cancelled"
	default:
		return false
	}
}
