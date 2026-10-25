// expect: AEG-TAINT-XSS
export function Banner() {
  const q = useSearchParams().get("q");
  return <div dangerouslySetInnerHTML={{ __html: `Results for ${q}` }} />;
}
