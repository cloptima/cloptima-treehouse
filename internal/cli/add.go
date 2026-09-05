package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cloptima/cloptima-treehouse/internal/config"
	"github.com/spf13/cobra"
)

var skipDirsWhenScanning = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".next":        true,
}

func isGitRepo(path string) bool {
	info, err := os.Stat(filepath.Join(path, ".git"))
	return err == nil && (info.IsDir() || info.Mode().IsRegular()) // regular file: a worktree/submodule gitdir pointer
}

// findRepos walks root looking for git repos, never descending into a repo
// it already found (avoids treating a submodule as a second registration)
// or into common heavy directories.
func findRepos(root string) ([]string, error) {
	var repos []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if path != root && skipDirsWhenScanning[d.Name()] {
			return filepath.SkipDir
		}
		if isGitRepo(path) {
			repos = append(repos, path)
			return filepath.SkipDir
		}
		return nil
	})
	return repos, err
}

func newAddCommand() *cobra.Command {
	var all string
	cmd := &cobra.Command{
		Use:   "add [path]",
		Short: "Register a repo (or, with --all, every repo under a directory) to watch",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			var candidates []string
			switch {
			case all != "":
				found, err := findRepos(all)
				if err != nil {
					return err
				}
				if len(found) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "no repos found under %s\n", all)
					return nil
				}
				candidates = found
			case len(args) == 1:
				abs, err := filepath.Abs(args[0])
				if err != nil {
					return err
				}
				if !isGitRepo(abs) {
					return fmt.Errorf("%s is not a git repo (no .git found)", abs)
				}
				candidates = []string{abs}
			default:
				return fmt.Errorf("provide a repo path, or --all <root>")
			}

			added := 0
			for _, path := range candidates {
				if cfg.AddRepo(path) {
					added++
					fmt.Fprintf(cmd.OutOrStdout(), "added %s\n", path)
				}
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d repo(s) registered (%d new)\n", len(cfg.Repos), added)
			return nil
		},
	}
	cmd.Flags().StringVar(&all, "all", "", "Register every repo found under this directory, instead of a single path")
	return cmd
}
