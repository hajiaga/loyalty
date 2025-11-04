import { useEffect, useState } from 'react';
import Layout from '@/components/Layout';
import { billAPI, propertyAPI } from '@/utils/api';
import toast from 'react-hot-toast';
import { format } from 'date-fns';

interface Bill {
  _id: string;
  property_id: string;
  property_name?: string;
  property_address?: string;
  tenant_name?: string;
  amount: number;
  status: 'pending' | 'paid' | 'overdue' | 'cancelled';
  billing_period_start: string;
  billing_period_end: string;
  due_date: string;
  description?: string;
}

interface Property {
  _id: string;
  name: string;
  address: string;
}

export default function Bills() {
  const [bills, setBills] = useState<Bill[]>([]);
  const [properties, setProperties] = useState<Property[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [formData, setFormData] = useState({
    property_id: '',
    billing_period_start: '',
    billing_period_end: '',
    due_date: '',
    description: '',
  });

  useEffect(() => {
    fetchBills();
    fetchProperties();
  }, [filterStatus]);

  const fetchBills = async () => {
    try {
      const response = await billAPI.getAll(filterStatus);
      setBills(response.data);
    } catch (error) {
      toast.error('Failed to load bills');
    } finally {
      setLoading(false);
    }
  };

  const fetchProperties = async () => {
    try {
      const response = await propertyAPI.getAll();
      setProperties(response.data);
    } catch (error) {
      toast.error('Failed to load properties');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      await billAPI.create({
        ...formData,
        billing_period_start: new Date(formData.billing_period_start).toISOString(),
        billing_period_end: new Date(formData.billing_period_end).toISOString(),
        due_date: new Date(formData.due_date).toISOString(),
      });
      toast.success('Bill created successfully');
      setShowModal(false);
      resetForm();
      fetchBills();
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to create bill');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this bill?')) return;

    try {
      await billAPI.delete(id);
      toast.success('Bill deleted successfully');
      fetchBills();
    } catch (error) {
      toast.error('Failed to delete bill');
    }
  };

  const handleUpdateStatus = async (id: string, status: string) => {
    try {
      await billAPI.update(id, { status });
      toast.success('Bill status updated');
      fetchBills();
    } catch (error) {
      toast.error('Failed to update bill status');
    }
  };

  const resetForm = () => {
    setFormData({
      property_id: '',
      billing_period_start: '',
      billing_period_end: '',
      due_date: '',
      description: '',
    });
  };

  const getStatusBadge = (status: string) => {
    const badges = {
      pending: 'badge-warning',
      paid: 'badge-success',
      overdue: 'badge-danger',
      cancelled: 'badge-info',
    };
    return `badge ${badges[status as keyof typeof badges] || 'badge-info'}`;
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-gray-900">Bills</h1>
          <div className="flex gap-3">
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="input max-w-xs"
            >
              <option value="">All Status</option>
              <option value="pending">Pending</option>
              <option value="paid">Paid</option>
              <option value="overdue">Overdue</option>
              <option value="cancelled">Cancelled</option>
            </select>
            <button onClick={() => setShowModal(true)} className="btn btn-primary">
              + Create Bill
            </button>
          </div>
        </div>

        {loading ? (
          <div className="text-center py-12">Loading...</div>
        ) : bills.length === 0 ? (
          <div className="card text-center py-12">
            <p className="text-gray-500 mb-4">No bills found</p>
            <button onClick={() => setShowModal(true)} className="btn btn-primary">
              Create your first bill
            </button>
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
                    <th className="table-header">Due Date</th>
                    <th className="table-header">Status</th>
                    <th className="table-header">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {bills.map((bill) => (
                    <tr key={bill._id} className="hover:bg-gray-50">
                      <td className="table-cell">
                        <div>
                          <p className="font-medium">{bill.property_name}</p>
                          <p className="text-gray-500 text-xs">{bill.property_address}</p>
                        </div>
                      </td>
                      <td className="table-cell">{bill.tenant_name || '-'}</td>
                      <td className="table-cell">
                        <span className="font-bold text-primary">${bill.amount.toFixed(2)}</span>
                      </td>
                      <td className="table-cell">
                        <div className="text-sm">
                          {format(new Date(bill.billing_period_start), 'MMM dd')} -{' '}
                          {format(new Date(bill.billing_period_end), 'MMM dd, yyyy')}
                        </div>
                      </td>
                      <td className="table-cell">
                        {format(new Date(bill.due_date), 'MMM dd, yyyy')}
                      </td>
                      <td className="table-cell">
                        <span className={getStatusBadge(bill.status)}>
                          {bill.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="table-cell">
                        <div className="flex gap-2">
                          {bill.status === 'pending' && (
                            <button
                              onClick={() => handleUpdateStatus(bill._id, 'paid')}
                              className="text-success hover:text-green-700 font-medium text-sm"
                            >
                              Mark Paid
                            </button>
                          )}
                          <button
                            onClick={() => handleDelete(bill._id)}
                            className="text-danger hover:text-red-700 font-medium text-sm"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-xl p-6 max-w-md w-full">
              <h2 className="text-2xl font-bold mb-6">Create New Bill</h2>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="label">Property</label>
                  <select
                    value={formData.property_id}
                    onChange={(e) => setFormData({ ...formData, property_id: e.target.value })}
                    className="input"
                    required
                  >
                    <option value="">Select a property</option>
                    {properties.map((property) => (
                      <option key={property._id} value={property._id}>
                        {property.name} - {property.address}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="label">Billing Period Start</label>
                  <input
                    type="date"
                    value={formData.billing_period_start}
                    onChange={(e) =>
                      setFormData({ ...formData, billing_period_start: e.target.value })
                    }
                    className="input"
                    required
                  />
                </div>

                <div>
                  <label className="label">Billing Period End</label>
                  <input
                    type="date"
                    value={formData.billing_period_end}
                    onChange={(e) =>
                      setFormData({ ...formData, billing_period_end: e.target.value })
                    }
                    className="input"
                    required
                  />
                </div>

                <div>
                  <label className="label">Due Date</label>
                  <input
                    type="date"
                    value={formData.due_date}
                    onChange={(e) => setFormData({ ...formData, due_date: e.target.value })}
                    className="input"
                    required
                  />
                </div>

                <div>
                  <label className="label">Description (Optional)</label>
                  <textarea
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    className="input"
                    rows={3}
                    placeholder="Additional notes..."
                  />
                </div>

                <div className="flex gap-3 pt-4">
                  <button type="submit" className="btn btn-primary flex-1">
                    Create Bill
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowModal(false);
                      resetForm();
                    }}
                    className="btn btn-secondary flex-1"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
