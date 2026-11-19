/**
 * Dashboard loading skeleton — shown instantly while the page JS loads.
 * This gives the user immediate visual feedback on route transitions.
 */
export default function DashboardLoading() {
  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: '32px 24px' }}>
      {/* Header skeleton */}
      <div style={{ marginBottom: 32 }}>
        <div className="skeleton" style={{ width: 120, height: 28, marginBottom: 8 }} />
        <div className="skeleton" style={{ width: 240, height: 36, marginBottom: 6 }} />
        <div className="skeleton" style={{ width: 320, height: 16 }} />
      </div>
      {/* Stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="skeleton" style={{ height: 112, borderRadius: 'var(--radius-md)' }} />
        ))}
      </div>
      {/* Chart + sidebar */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 24 }}>
        <div className="skeleton" style={{ height: 280, borderRadius: 'var(--radius-md)' }} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="skeleton" style={{ height: 130, borderRadius: 'var(--radius-md)' }} />
          <div className="skeleton" style={{ height: 130, borderRadius: 'var(--radius-md)' }} />
        </div>
      </div>
    </div>
  );
}
