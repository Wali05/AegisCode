// expect: none
export function Banner() {
  const q = useSearchParams().get("q") ?? "";
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(q) }} />;
}
