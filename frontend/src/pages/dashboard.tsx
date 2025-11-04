import { useEffect, useState } from 'react';
import Layout from '@/components/Layout';
import { reportsAPI } from '@/utils/api';
import toast from 'react-hot-toast';

interface Summary {
  total_properties: number;
  total_bills: number;
  total_amount_due: number;
  total_amount_paid: number;
  total_outstanding: number;
  overdue_bills: number;
  pending_bills: number;
  paid_bills: number;
}

export default function Dashboard() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSummary();
  }, []);

  const fetchSummary = async () => {
    try {
      const response = await reportsAPI.getSummary();
      setSummary(response.data);
    } catch (error: any) {
      toast.error('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-64">
          <div className="text-gray-500">Loading...</div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="card border-l-4 border-primary">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Total Properties</p>
                <p className="text-3xl font-bold text-gray-900 mt-2">
                  {summary?.total_properties || 0}
                </p>
              </div>
              <div className="text-4xl">🏢</div>
            </div>
          </div>

          <div className="card border-l-4 border-success">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Amount Paid</p>
                <p className="text-3xl font-bold text-success mt-2">
                  ${summary?.total_amount_paid.toFixed(2) || '0.00'}
                </p>
              </div>
              <div className="text-4xl">💰</div>
            </div>
          </div>

          <div className="card border-l-4 border-yellow-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Outstanding</p>
                <p className="text-3xl font-bold text-yellow-600 mt-2">
                  ${summary?.total_outstanding.toFixed(2) || '0.00'}
                </p>
              </div>
              <div className="text-4xl">⏳</div>
            </div>
          </div>

          <div className="card border-l-4 border-danger">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Overdue Bills</p>
                <p className="text-3xl font-bold text-danger mt-2">
                  {summary?.overdue_bills || 0}
                </p>
              </div>
              <div className="text-4xl">⚠️</div>
            </div>
          </div>
        </div>

        {/* Bills Summary */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="card">
            <h3 className="text-xl font-bold text-gray-900 mb-4">Bills Overview</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                    <span className="text-2xl">📊</span>
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">Total Bills</p>
                    <p className="text-sm text-gray-500">All bills created</p>
                  </div>
                </div>
                <span className="text-2xl font-bold text-blue-600">
                  {summary?.total_bills || 0}
                </span>
              </div>

              <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                    <span className="text-2xl">✅</span>
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">Paid Bills</p>
                    <p className="text-sm text-gray-500">Successfully paid</p>
                  </div>
                </div>
                <span className="text-2xl font-bold text-success">
                  {summary?.paid_bills || 0}
                </span>
              </div>

              <div className="flex items-center justify-between p-4 bg-yellow-50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center">
                    <span className="text-2xl">⏰</span>
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">Pending Bills</p>
                    <p className="text-sm text-gray-500">Awaiting payment</p>
                  </div>
                </div>
                <span className="text-2xl font-bold text-yellow-600">
                  {summary?.pending_bills || 0}
                </span>
              </div>
            </div>
          </div>

          <div className="card">
            <h3 className="text-xl font-bold text-gray-900 mb-4">Quick Actions</h3>
            <div className="space-y-3">
              <a
                href="/properties"
                className="block p-4 bg-primary/5 hover:bg-primary/10 rounded-lg transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">🏢</span>
                  <div>
                    <p className="font-medium text-gray-900">Manage Properties</p>
                    <p className="text-sm text-gray-500">Add, edit, or remove properties</p>
                  </div>
                </div>
              </a>

              <a
                href="/bills"
                className="block p-4 bg-primary/5 hover:bg-primary/10 rounded-lg transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">📄</span>
                  <div>
                    <p className="font-medium text-gray-900">Create Bill</p>
                    <p className="text-sm text-gray-500">Generate new billing invoice</p>
                  </div>
                </div>
              </a>

              <a
                href="/reports"
                className="block p-4 bg-primary/5 hover:bg-primary/10 rounded-lg transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">📈</span>
                  <div>
                    <p className="font-medium text-gray-900">View Reports</p>
                    <p className="text-sm text-gray-500">Analyze payment trends</p>
                  </div>
                </div>
              </a>

              <a
                href="/payments"
                className="block p-4 bg-primary/5 hover:bg-primary/10 rounded-lg transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">💳</span>
                  <div>
                    <p className="font-medium text-gray-900">Payment History</p>
                    <p className="text-sm text-gray-500">View all transactions</p>
                  </div>
                </div>
              </a>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
