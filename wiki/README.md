# Wiki source

Markdown here is the source for the [GitHub wiki](https://github.com/mverschu/adwsdomaindump/wiki).

## Publish / update

```sh
git clone git@github.com:mverschu/adwsdomaindump.wiki.git
rsync -av --exclude README.md /path/to/adwsdomaindump/wiki/ /path/to/adwsdomaindump.wiki/
cd /path/to/adwsdomaindump.wiki
git add -A
git commit -m "Update wiki"
git push
```

`Home.md` becomes the wiki home page. Other filenames become page titles (hyphens → spaces).
