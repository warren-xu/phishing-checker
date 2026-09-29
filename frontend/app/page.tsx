import { Checker } from "./components/Checker";

export default function Home() {
  return (
    <>
      <header>
        <div>
          <p className="kicker">Phishing checker</p>
          <h1>Phishing Checker</h1>
        </div>
      </header>
      <Checker />
    </>
  );
}
