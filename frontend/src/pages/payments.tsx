import { useEffect, useState } from 'react';
import Layout from '@/components/Layout';
import { paymentAPI } from '@/utils/api';
import toast from 'react-hot-toast';
import { format } from 'date-fns';

interface Payment {
  _id: string;
  bill_id: string;
  property_id: string;
  property_name?: string;
  tenant_name?: string;
  amount: number;
  payment_method: string;
  status: string;
  paid_at?: string;
  bill_period_start?: string;
  bill_period_end?: string;
}

export default function Payments() {
  const [payments, setPayments] = useState<Payment[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchPayments();
  }, []);

  const fetchPayments = async () => {
    try {
      const response = await paymentAPI.getAll();
      setPayments(response.data);
    } catch (error) {
      toast.error('Failed to load payments');
    } finally {
      setLoading(false);
    }
  };

  const getPaymentMethodBadge = (method: string) => {
    const badges: { [key: string]: string } = {
      stripe: 'badge-info',
      cash: 'badge-success',
      bank_transfer: 'badge-warning',
    };
    return `badge ${badges[method] || 'badge-info'}`;
  };

  const getStatusBadge = (status: string) => {
    const badges: { [key: string]: string } = {
      completed: 'badge-success',
      pending: 'badge-warning',
      failed: 'badge-danger',
      refunded: 'badge-info',
    };
    return `badge ${badges[status] || 'badge-info'}`;
  };

  const totalAmount = payments.reduce((sum, payment) => sum + payment.amount, 0);

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-gray-900">Payment History</h1>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="card border-l-4 border-success">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Total Payments</p>
                <p className="text-3xl font-bold text-gray-900 mt-2">{payments.length}</p>
              </div>
              <div className="text-4xl">💳</div>
            </div>
          </div>

          <div className="card border-l-4 border-primary">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Total Amount</p>
                <p className="text-3xl font-bold text-primary mt-2">${totalAmount.toFixed(2)}</p>
              </div>
              <div className="text-4xl">💰</div>
            </div>
          </div>

          <div className="card border-l-4 border-success">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm font-medium">Completed</p>
                <p className="text-3xl font-bold text-success mt-2">
                  {payments.filter((p) => p.status === 'completed').length}
                </p>
              </div>
              <div className="text-4xl">✅</div>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="text-center py-12">Loading...</div>
        ) : payments.length === 0 ? (
          <div className="card text-center py-12">
            <p className="text-4xl mb-4">💳</p>
            <p className="text-gray-500 mb-2">No payments recorded yet</p>
            <p className="text-sm text-gray-400">Payments will appear here once bills are paid</p>
          </div>
        ) : (
          <div className="card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="table">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="table-header">Property</th>
                    <th className="table-header">Tenant</th>
                    <th className="table-header">Amount</th>
                    <th className="table-header">Billing Period</th>
                    <th className="table-header">Payment Date</th>
                    <th className="table-header">Method</th>
                    <th className="table-header">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {payments.map((payment) => (
                    <tr key={payment._id} className="hover:bg-gray-50">
                      <td className="table-cell">
                        <p className="font-medium">{payment.property_name || '-'}</p>
                      </td>
                      <td className="table-cell">{payment.tenant_name || '-'}</td>
                      <td className="table-cell">
                        <span className="font-bold text-success">${payment.amount.toFixed(2)}</span>
                      </td>
                      <td className="table-cell">
                        {payment.bill_period_start && payment.bill_period_end ? (
                          <div className="text-sm">
                            {format(new Date(payment.bill_period_start), 'MMM dd')} -{' '}
                            {format(new Date(payment.bill_period_end), 'MMM dd, yyyy')}
                          </div>
                        ) : (
                          '-'
                        )}
                      </td>
                      <td className="table-cell">
                        {payment.paid_at
                          ? format(new Date(payment.paid_at), 'MMM dd, yyyy HH:mm')
                          : '-'}
                      </td>
                      <td className="table-cell">
                        <span className={getPaymentMethodBadge(payment.payment_method)}>
                          {payment.payment_method.replace('_', ' ').toUpperCase()}
                        </span>
                      </td>
                      <td className="table-cell">
                        <span className={getStatusBadge(payment.status)}>
                          {payment.status.toUpperCase()}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
