import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { confirmForgotPassword } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';

interface LocationState {
  username: string;
}

const ConfirmForgotPasswordPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState;
  const username = state?.username || '';
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await confirmForgotPassword(username, code, newPassword);
      navigate('/signin');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Reset Password</h2>
      <TextInput label="Code" value={code} onChange={e => setCode(e.target.value)} placeholder="Verification code" />
      <TextInput label="New Password" type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder="New password" />
      <Button type="submit" loading={loading}>Reset Password</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signin" className="auth-link">Back to Sign In</Link>
      </div>
    </form>
  );
};

export default ConfirmForgotPasswordPage; 