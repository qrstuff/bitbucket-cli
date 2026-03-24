package factory

import (
	"github.com/qrstuff/bitbucket-cli/internal/config"
	"github.com/qrstuff/bitbucket-cli/pkg/browser"
	"github.com/qrstuff/bitbucket-cli/pkg/cmdutil"
	"github.com/qrstuff/bitbucket-cli/pkg/iostreams"
	"github.com/qrstuff/bitbucket-cli/pkg/pager"
	"github.com/qrstuff/bitbucket-cli/pkg/progress"
	"github.com/qrstuff/bitbucket-cli/pkg/prompter"
)

// New constructs a command factory following gh/jk idioms.
func New(appVersion string) (*cmdutil.Factory, error) {
	ios := iostreams.System()

	f := &cmdutil.Factory{
		AppVersion:     appVersion,
		ExecutableName: "bkt",
		IOStreams:      ios,
	}

	f.Browser = browser.NewSystem()
	f.Pager = pager.NewSystem(ios)
	f.Prompter = prompter.New(ios)
	f.Spinner = progress.NewSpinner(ios)

	f.Config = config.Load

	return f, nil
}
