import { redirect } from "next/navigation";

import { DEFAULT_AFTER_LOGIN } from "@/lib/redirect";

/** The dashboard is the home page; middleware sends signed-out visitors to /login. */
export default function Home(): never {
  redirect(DEFAULT_AFTER_LOGIN);
}
