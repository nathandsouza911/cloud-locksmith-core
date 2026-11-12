import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { AuthProvider } from "@/lib/auth-context";
import { DemoBanner } from "@/components/DemoBanner";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Cloud Locksmith Core",
  description: "Microsoft 365 identity posture scanning with approval-gated remediation.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} antialiased`}>
        <DemoBanner />
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
