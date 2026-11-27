import { splitPlaceholders } from '../lib/privacy';
import { LAST_UPDATED, PRIVACY_SECTIONS } from '../lib/privacy-content';

export function PrivacyPage() {
  return (
    <div className="prose-page">
      <div className="page-head">
        <h1>Privacy</h1>
        <span className="muted">Last updated {LAST_UPDATED}</span>
      </div>
      {PRIVACY_SECTIONS.map((s) => (
        <section key={s.id} aria-labelledby={`privacy-${s.id}`}>
          <h2 id={`privacy-${s.id}`}>{s.title}</h2>
          {s.statements.map((st) => (
            <p key={st.text}>
              {splitPlaceholders(st.text).map((p) =>
                p.placeholder ? (
                  <mark key={p.text} className="owner-placeholder">
                    {p.text}
                  </mark>
                ) : (
                  p.text
                ),
              )}
            </p>
          ))}
        </section>
      ))}
    </div>
  );
}
