import React from 'react';

export interface TextInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
}

const TextInput: React.FC<TextInputProps> = ({ label, className, ...props }) => {
  return (
    <div className={`auth-input-wrapper ${className}`}>
      {label && <label>{label}</label>}
      <input {...props} className="auth-input" />
    </div>
  );
};

export default TextInput; 