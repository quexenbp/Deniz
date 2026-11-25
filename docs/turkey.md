# Turkish sources and language

## Automated

- `kap` searches KAP disclosures (`memberDisclosureQuery`, the public endpoint
  behind the site's search page).
- `uyap` searches UYAP Emsal docket metadata; each result links to the readable
  decision page.

```bash
deniz run kap "tahsis" --type keyword
deniz run uyap "tahliye" --type keyword
```

Both are HTML/JSON scrapers: KAP sits behind a WAF and may answer `Blocked` or
`ParseChanged`. Treat `ParseChanged` as a signal that the upstream shape moved,
not as "no results".

## Not automated

- MERSİS company query requires e-Devlet authentication.
- Türkiye Ticaret Sicili Gazetesi unvan/ilan search is captcha-gated.

Neither has a documented public API. Use them manually and attach the result
to a case with `deniz case add` or `deniz import`.

## Language

`deniz report --lang tr` and `deniz case export --lang tr` render Turkish
HTML labels. `DENIZ_LANG=tr` sets the default. The CLI itself, JSON fields and
STIX labels stay English, so machine consumers are unaffected.
