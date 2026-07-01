# Wiki source

Markdown here is the source for the [GitHub wiki](https://github.com/mverschu/adwsdomaindump/wiki).

## Publish / update

### Automatic (recommended)

Pushes to `main` that change `wiki/**` run the [Sync wiki](https://github.com/mverschu/adwsdomaindump/actions/workflows/wiki-sync.yml) workflow.

**One-time:** GitHub creates the wiki git repo only after the first page exists. Open [Create wiki page](https://github.com/mverschu/adwsdomaindump/wiki/_new), title **Home**, save with any placeholder text, then run **Sync wiki** from Actions (or push a wiki change).

If the workflow gets **403** on push, add repo secret `WIKI_PUSH_TOKEN` (PAT with **Contents: read and write** on this repo).

### Manual (SSH)

After the first wiki page exists:

```sh
git clone git@github.com:mverschu/adwsdomaindump.wiki.git
cp wiki/*.md adwsdomaindump.wiki/
rm -f adwsdomaindump.wiki/README.md
cd adwsdomaindump.wiki
git add -A
git commit -m "Update wiki"
git push
```

`Home.md` becomes the wiki home page. Other filenames become page titles (hyphens → spaces).
