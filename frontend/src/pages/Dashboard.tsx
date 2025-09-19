import React from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

const Dashboard: React.FC = () => {
  const { user, logout } = useAuth();

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-2xl mx-auto">
        <Card>
          <CardHeader>
            <CardTitle>Welcome to your Dashboard!</CardTitle>
            <CardDescription>
              You have successfully authenticated with our system.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <h3 className="text-lg font-medium">User Information</h3>
              <div className="bg-gray-100 p-4 rounded-md">
                <p><strong>Username:</strong> {user?.username}</p>
                <p><strong>Email:</strong> {user?.email}</p>
                <p><strong>User ID:</strong> {user?.id}</p>
              </div>
            </div>
            <div className="space-y-2">
              <h3 className="text-lg font-medium">Authentication Status</h3>
              <div className="bg-green-100 p-4 rounded-md">
                <p className="text-green-800">✅ Successfully authenticated</p>
                <p className="text-sm text-green-600">
                  Your JWT token is stored in an HTTP-only cookie and is automatically sent with each request.
                </p>
              </div>
            </div>
            <div className="pt-4">
              <Button onClick={handleLogout} variant="outline">
                Sign Out
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Dashboard;
