package source

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewGitIdentifier(t *testing.T) {
	tests := []struct {
		url      string
		expected GitIdentifier
	}{
		{
			url: "ssh://root@subdomain.example.hostname:2222/root/my/really/weird/path/foo.git",
			expected: GitIdentifier{
				Remote: "ssh://root@subdomain.example.hostname:2222/root/my/really/weird/path/foo.git",
			},
		},
		{
			url: "ssh://root@subdomain.example.hostname:2222/root/my/really/weird/path/foo.git#main",
			expected: GitIdentifier{
				Remote: "ssh://root@subdomain.example.hostname:2222/root/my/really/weird/path/foo.git",
				Ref:    "main",
			},
		},
		{
			url: "git@github.com:moby/buildkit.git",
			expected: GitIdentifier{
				Remote: "git@github.com:moby/buildkit.git",
			},
		},
		{
			url: "github.com/moby/buildkit.git#main",
			expected: GitIdentifier{
				Remote: "https://github.com/moby/buildkit.git",
				Ref:    "main",
			},
		},
		{
			url: "git://github.com/user/repo.git",
			expected: GitIdentifier{
				Remote: "git://github.com/user/repo.git",
			},
		},
		{
			url: "git://github.com/user/repo.git#mybranch:mydir/mysubdir/",
			expected: GitIdentifier{
				Remote: "git://github.com/user/repo.git",
				Ref:    "mybranch",
				Subdir: "mydir/mysubdir/",
			},
		},
		{
			url: "git://github.com/user/repo.git#:mydir/mysubdir/",
			expected: GitIdentifier{
				Remote: "git://github.com/user/repo.git",
				Subdir: "mydir/mysubdir/",
			},
		},
		{
			url: "https://github.com/user/repo.git",
			expected: GitIdentifier{
				Remote: "https://github.com/user/repo.git",
			},
		},
		{
			url: "https://github.com/user/repo.git#mybranch:mydir/mysubdir/",
			expected: GitIdentifier{
				Remote: "https://github.com/user/repo.git",
				Ref:    "mybranch",
				Subdir: "mydir/mysubdir/",
			},
		},
		{
			url: "git@github.com:user/repo.git",
			expected: GitIdentifier{
				Remote: "git@github.com:user/repo.git",
			},
		},
		{
			url: "git@github.com:user/repo.git#mybranch:mydir/mysubdir/",
			expected: GitIdentifier{
				Remote: "git@github.com:user/repo.git",
				Ref:    "mybranch",
				Subdir: "mydir/mysubdir/",
			},
		},
		{
			url: "ssh://github.com/user/repo.git",
			expected: GitIdentifier{
				Remote: "ssh://github.com/user/repo.git",
			},
		},
		{
			url: "ssh://github.com/user/repo.git#mybranch:mydir/mysubdir/",
			expected: GitIdentifier{
				Remote: "ssh://github.com/user/repo.git",
				Ref:    "mybranch",
				Subdir: "mydir/mysubdir/",
			},
		},
		{
			url: "ssh://foo%40barcorp.com@github.com/user/repo.git#mybranch:mydir/mysubdir/",
			expected: GitIdentifier{
				Remote: "ssh://foo%40barcorp.com@github.com/user/repo.git",
				Ref:    "mybranch",
				Subdir: "mydir/mysubdir/",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.url, func(t *testing.T) {
			gi, err := NewGitIdentifier(tt.url)
			require.NoError(t, err)
			require.Equal(t, tt.expected, *gi)
		})
	}
}

// TestValidateGitRef_CVE_2026_33748 verifies that refs starting with '-' are
// rejected at identifier construction time (CVE-2026-33748 hardening).
func TestValidateGitRef_CVE_2026_33748(t *testing.T) {
	t.Parallel()

	rejectCases := []string{"-u", "--upload-pack=evil", "-"}
	for _, ref := range rejectCases {
		ref := ref
		t.Run(ref, func(t *testing.T) {
			t.Parallel()
			_, err := NewGitIdentifier("https://github.com/foo/bar.git#" + ref)
			require.Error(t, err, "expected error for ref %q", ref)
		})
	}

	acceptCases := []string{"main", "v1.0.0", "abc123def", "feature/my-branch"}
	for _, ref := range acceptCases {
		ref := ref
		t.Run(ref, func(t *testing.T) {
			t.Parallel()
			_, err := NewGitIdentifier("https://github.com/foo/bar.git#" + ref)
			require.NoError(t, err, "expected no error for ref %q", ref)
		})
	}
}
