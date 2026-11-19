/**
 * Results loading skeleton — shown instantly while the results page JS loads.
 */
export default function ResultsLoading() {
  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: '32px 24px' }}>
      <div style={{ marginBottom: 32 }}>
        <div className="skeleton" style={{ width: 100, height: 28, marginBottom: 8 }} />
        <div className="skeleton" style={{ width: 200, height: 36, marginBottom: 6 }} />
        <div className="skeleton" style={{ width: 360, height: 16 }} />
      </div>
      {/* Executive summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="skeleton" style={{ height: 128, borderRadius: 'var(--radius-md)' }} />
        ))}
      </div>
      {/* Chart area */}
      <div className="skeleton" style={{ height: 260, borderRadius: 'var(--radius-md)', marginBottom: 24 }} />
      {/* Table */}
      <div className="skeleton" style={{ height: 400, borderRadius: 'var(--radius-md)' }} />
    </div>
  );
}
