package net

type Feature uint64

const (
	FeatureNetCSUM              Feature = 1 << 0
	FeatureNetGuestCSUM         Feature = 1 << 1
	FeatureNetCtrlGuestOffloads Feature = 1 << 2
	FeatureNetMTU               Feature = 1 << 3
	FeatureNetMAC               Feature = 1 << 5
	FeatureNetGSO               Feature = 1 << 6
	FeatureNetGuestRSC4         Feature = 1 << 41
	FeatureNetGuestRSC6         Feature = 1 << 42
	FeatureNetGuestTSO4         Feature = 1 << 7
	FeatureNetGuestTSO6         Feature = 1 << 8
	FeatureNetGuestECN          Feature = 1 << 9
	FeatureNetGuestUFO          Feature = 1 << 10
	FeatureNetHostTSO4          Feature = 1 << 11
	FeatureNetHostTSO6          Feature = 1 << 12
	FeatureNetHostECN           Feature = 1 << 13
	FeatureNetHostUFO           Feature = 1 << 14
	FeatureNetMergeRXBuffers    Feature = 1 << 15
	FeatureNetStatus            Feature = 1 << 16
	FeatureNetCtrlVQ            Feature = 1 << 17
	FeatureNetCtrlRX            Feature = 1 << 18
	FeatureNetCtrlVLAN          Feature = 1 << 19
	FeatureNetGuestAnnounce     Feature = 1 << 21
	FeatureNetMQ                Feature = 1 << 22
	FeatureNetCtrlMacAddr       Feature = 1 << 23
	FeatureNetHostUSO           Feature = 1 << 56
	FeatureNetHashReport        Feature = 1 << 57
	FeatureNetGuestHdrLen       Feature = 1 << 59
	FeatureNetRSS               Feature = 1 << 60
	FeatureNetRSCExt            Feature = 1 << 61
	FeatureNetStandby           Feature = 1 << 62
	FeatureNetSpeedDuplex       Feature = 1 << 63
)
const (
	FeatureIndirectDesc     Feature = 1 << 28
	FeatureEventIdx         Feature = 1 << 29
	FeatureVersion1         Feature = 1 << 32
	FeatureAccessPlatform   Feature = 1 << 33
	FeatureRingPacked       Feature = 1 << 34
	FeatureInOrder          Feature = 1 << 35
	FeatureOrderPlatform    Feature = 1 << 36
	FeatureSRIOV            Feature = 1 << 37
	FeatureNotificationData Feature = 1 << 38
	FeatureNotifConfigData  Feature = 1 << 39
	FeatureRingReset        Feature = 1 << 40
)
