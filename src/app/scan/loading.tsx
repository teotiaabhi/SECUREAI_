/**
 * Scan page loading skeleton.
 */
export default function ScanLoading() {
  return (
    <div style={{ maxWidth: 800, margin: '0 auto', padding: '32px 24px' }}>
      <div style={{ marginBottom: 32 }}>
        <div className="skeleton" style={{ width: 100, height: 28, marginBottom: 8 }} />
        <div className="skeleton" style={{ width: 280, height: 36, marginBottom: 6 }} />
        <div className="skeleton" style={{ width: 360, height: 16 }} />
      </div>
      {/* Scan mode cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 24 }}>
        {[1, 2, 3].map((i) => (
          <div key={i} className="skeleton" style={{ height: 160, borderRadius: 'var(--radius-md)' }} />
        ))}
      </div>
      <div className="skeleton" style={{ height: 300, borderRadius: 'var(--radius-md)' }} />
    </div>
  );
}
