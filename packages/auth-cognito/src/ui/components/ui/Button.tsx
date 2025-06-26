import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  loading?: boolean;
}

const Button: React.FC<ButtonProps> = ({ loading, children, disabled, className, ...props }) => (
  <button
    {...props}
    disabled={loading || disabled}
    className={`auth-button ${className}`}
  >
    {loading ? 'Loading...' : children}
  </button>
);

export default Button; 