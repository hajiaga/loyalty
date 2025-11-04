import { useEffect, useState } from 'react';
import Layout from '@/components/Layout';
import { reportsAPI } from '@/utils/api';
import toast from 'react-hot-toast';
import { format } from 'date-fns';

interface PropertyReport {
  property_id: string;
  property_name: string;
  property_address: string;
  tenant_name?: string;
  total_bills: number;
  total_paid: number;
  total_outstanding: number;
  last_payment_date?: string;
}

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

export default function Reports() {
  const [propertyReports, setPropertyReports] = useState<PropertyReport[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const [summaryRes, propertyRes] = await Promise.all([
        reportsAPI.getSummary(),
        reportsAPI.getPropertyReports(),
      ]);
      setSummary(summaryRes.data);
      setPropertyReports(propertyRes.data);
    } catch (error) {
      toast.error('Failed to load reports');
    } finally {
      setLoading(false);
    }
  };

  const collectionRate = summary
    ? ((summary.total_amount_paid / (summary.total_amount_paid + summary.total_outstanding)) * 100).toFixed(1)
    : '0';

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-gray-900">Reports & Analytics</h1>
        </div>

        {loading ? (
          <div className="text-center py-12">Loading...</div>
        ) : (
          <>
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="card border-l-4 border-primary">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-500 text-sm font-medium">Total Revenue</p>
                    <p className="text-3xl font-bold text-primary mt-2">
                      ${summary?.total_amount_paid.toFixed(2)}
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
                      ${summary?.total_outstanding.toFixed(2)}
                    </p>
                  </div>
                  <div className="text-4xl">⏳</div>
                </div>
              </div>

              <div className="card border-l-4 border-success">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-500 text-sm font-medium">Collection Rate</p>
                    <p className="text-3xl font-bold text-success mt-2">{collectionRate}%</p>
                  </div>
                  <div className="text-4xl">📈</div>
                </div>
              </div>

              <div className="card border-l-4 border-danger">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-500 text-sm font-medium">Overdue Bills</p>
                    <p className="text-3xl font-bold text-danger mt-2">{summary?.overdue_bills}</p>
                  </div>
                  <div className="text-4xl">⚠️</div>
                </div>
              </div>
            </div>

            {/* Bills Overview */}
            <div className="card">
              <h3 className="text-xl font-bold text-gray-900 mb-6">Bills Overview</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="text-center p-6 bg-green-50 rounded-lg">
                  <div className="text-4xl mb-2">✅</div>
                  <p className="text-3xl font-bold text-success">{summary?.paid_bills}</p>
                  <p className="text-gray-600 mt-1">Paid Bills</p>
                </div>

                <div className="text-center p-6 bg-yellow-50 rounded-lg">
                  <div className="text-4xl mb-2">⏰</div>
                  <p className="text-3xl font-bold text-yellow-600">{summary?.pending_bills}</p>
                  <p className="text-gray-600 mt-1">Pending Bills</p>
                </div>

                <div className="text-center p-6 bg-red-50 rounded-lg">
                  <div className="text-4xl mb-2">⚠️</div>
                  <p className="text-3xl font-bold text-danger">{summary?.overdue_bills}</p>
                  <p className="text-gray-600 mt-1">Overdue Bills</p>
                </div>
              </div>
            </div>

            {/* Property Reports */}
            <div className="card">
              <h3 className="text-xl font-bold text-gray-900 mb-6">Property Performance</h3>
              {propertyReports.length === 0 ? (
                <div className="text-center py-12 text-gray-500">No property data available</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="table">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="table-header">Property</th>
                        <th className="table-header">Tenant</th>
                        <th className="table-header">Total Bills</th>
                        <th className="table-header">Total Paid</th>
                        <th className="table-header">Outstanding</th>
                        <th className="table-header">Last Payment</th>
                        <th className="table-header">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200">
                      {propertyReports.map((report) => {
                        const collectionRate =
                          report.total_paid / (report.total_paid + report.total_outstanding);
                        const status =
                          collectionRate >= 0.8
                            ? 'Excellent'
                            : collectionRate >= 0.5
                            ? 'Good'
                            : 'Needs Attention';
                        const statusColor =
                          collectionRate >= 0.8
                            ? 'badge-success'
                            : collectionRate >= 0.5
                            ? 'badge-warning'
                            : 'badge-danger';

                        return (
                          <tr key={report.property_id} className="hover:bg-gray-50">
                            <td className="table-cell">
                              <div>
                                <p className="font-medium">{report.property_name}</p>
                                <p className="text-xs text-gray-500">{report.property_address}</p>
                              </div>
                            </td>
                            <td className="table-cell">{report.tenant_name || '-'}</td>
                            <td className="table-cell">
                              <span className="font-medium">{report.total_bills}</span>
                            </td>
                            <td className="table-cell">
                              <span className="font-bold text-success">
                                ${report.total_paid.toFixed(2)}
                              </span>
                            </td>
                            <td className="table-cell">
                              <span className="font-bold text-yellow-600">
                                ${report.total_outstanding.toFixed(2)}
                              </span>
                            </td>
                            <td className="table-cell">
                              {report.last_payment_date
                                ? format(new Date(report.last_payment_date), 'MMM dd, yyyy')
                                : 'Never'}
                            </td>
                            <td className="table-cell">
                              <span className={`badge ${statusColor}`}>{status}</span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Financial Summary */}
            <div className="card">
              <h3 className="text-xl font-bold text-gray-900 mb-6">Financial Summary</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center p-4 bg-gray-50 rounded-lg">
                  <span className="text-gray-700 font-medium">Total Revenue Collected</span>
                  <span className="text-2xl font-bold text-success">
                    ${summary?.total_amount_paid.toFixed(2)}
                  </span>
                </div>

                <div className="flex justify-between items-center p-4 bg-gray-50 rounded-lg">
                  <span className="text-gray-700 font-medium">Outstanding Amount</span>
                  <span className="text-2xl font-bold text-yellow-600">
                    ${summary?.total_outstanding.toFixed(2)}
                  </span>
                </div>

                <div className="flex justify-between items-center p-4 bg-gray-50 rounded-lg">
                  <span className="text-gray-700 font-medium">Total Expected Revenue</span>
                  <span className="text-2xl font-bold text-primary">
                    $
                    {(
                      (summary?.total_amount_paid || 0) + (summary?.total_outstanding || 0)
                    ).toFixed(2)}
                  </span>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </Layout>
  );
}
