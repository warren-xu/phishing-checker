import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Phishing Checker",
  description: "Phishing checker for email inboxes.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
