import { redirect } from "next/navigation";

/**
 * IR-SAM has no marketing landing page.  Visiting the root sends the
 * user straight to the login screen, which is the only public surface
 * of the application.
 */
export default function RootPage() {
  redirect("/login");
}
