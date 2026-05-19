import { Segmented } from "antd";

type Hours = 1 | 6 | 24 | 168;

interface TimeRangeSegmentedProps {
  value: Hours;
  onChange: (v: Hours) => void;
}

const OPTIONS: { label: string; value: Hours }[] = [
  { label: "1h", value: 1 },
  { label: "6h", value: 6 },
  { label: "24h", value: 24 },
  { label: "7d", value: 168 },
];

export const TimeRangeSegmented: React.FC<TimeRangeSegmentedProps> = ({ value, onChange }) => (
  <Segmented
    options={OPTIONS}
    value={value}
    onChange={(v) => onChange(v as Hours)}
  />
);
