/**
 * History page loading skeleton.
 */
export default function HistoryLoading() {
  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: '32px 24px' }}>
      <div style={{ marginBottom: 32 }}>
        <div className="skeleton" style={{ width: 120, height: 28, marginBottom: 8 }} />
        <div className="skeleton" style={{ width: 200, height: 36 }} />
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="skeleton" style={{ height: 80, borderRadius: 'var(--radius-md)' }} />
        ))}
      </div>
    </div>
  );
}
