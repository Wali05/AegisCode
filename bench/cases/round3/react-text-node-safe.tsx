// expect: none
"use client";
import { useSearchParams } from "next/navigation";
export function SearchHeading() {
  const q = useSearchParams().get("q");
  return <h1>Results for {q}</h1>;
}
