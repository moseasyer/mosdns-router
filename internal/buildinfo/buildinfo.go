package buildinfo

var (
	Version   = "dev"
	Revision  = "unknown"
	BuildTime = "unknown"
)

type Info struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	BuildTime string `json:"build_time"`
}

func Snapshot() Info {
	return Info{Version: Version, Revision: Revision, BuildTime: BuildTime}
}
