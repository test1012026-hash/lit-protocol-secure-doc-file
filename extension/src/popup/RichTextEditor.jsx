import React, { useMemo } from "react";
import ReactQuill from "react-quill";
import "react-quill/dist/quill.snow.css";

const TOOLBAR = [
  [{ header: [1, 2, 3, false] }],
  ["bold", "italic", "underline", "strike"],
  [{ list: "ordered" }, { list: "bullet" }],
  [{ color: [] }, { background: [] }],
  ["link"],
  ["clean"],
];

export default function RichTextEditor({
  value,
  onChange,
  placeholder = "Write your message…",
  disabled = false,
}) {
  const modules = useMemo(
    () => ({
      toolbar: TOOLBAR,
      clipboard: { matchVisual: false },
    }),
    [],
  );

  return (
    <div className={`rich-editor ${disabled ? "is-disabled" : ""}`}>
      <ReactQuill
        theme="snow"
        value={value || ""}
        onChange={(html) => onChange(html)}
        modules={modules}
        placeholder={placeholder}
        readOnly={disabled}
      />
    </div>
  );
}
