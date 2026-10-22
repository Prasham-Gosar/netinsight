// jsdom has no ResizeObserver; Recharts' ResponsiveContainer needs one.
class RO {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver || RO
