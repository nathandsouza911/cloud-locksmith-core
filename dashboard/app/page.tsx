import { redirect } from "next/navigation";

// The open-source edition has no marketing site: the root goes straight to sign-in.
export default function Home() {
  redirect("/login");
}
