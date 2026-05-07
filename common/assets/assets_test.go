package assets

import (
	"github.com/daeuniverse/dae/common/consts"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBuildSearchDirsUsesStableAssetFolder(t *testing.T) {
	oldAppName := consts.AppName
	consts.AppName = "daedrust"
	t.Cleanup(func() {
		consts.AppName = oldAppName
	})

	searchDirs := buildSearchDirs([]string{"/etc/daed"}, "")
	if runtime.GOOS == "windows" {
		if len(searchDirs) == 0 {
			t.Fatal("expected at least one search dir")
		}
		return
	}

	want := filepath.Join("/usr/local/share", consts.LocationAssetFolder)
	for _, dir := range searchDirs {
		if dir == want {
			return
		}
	}
	t.Fatalf("expected %q in %v", want, searchDirs)
}
