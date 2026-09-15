import "./globals.css";

export const metadata = {
  title: "xalgo-ops",
  description: "Authorized bug bounty command center"
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
