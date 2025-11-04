import { useEffect, useState } from 'react';
import Layout from '@/components/Layout';
import { propertyAPI } from '@/utils/api';
import toast from 'react-hot-toast';

interface Property {
  _id: string;
  name: string;
  address: string;
  calculation_type: 'per_sqm' | 'fixed';
  area_sqm?: number;
  rate_per_sqm?: number;
  fixed_rate?: number;
  tenant_name?: string;
  tenant_email?: string;
  tenant_phone?: string;
}

export default function Properties() {
  const [properties, setProperties] = useState<Property[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingProperty, setEditingProperty] = useState<Property | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    address: '',
    calculation_type: 'per_sqm' as 'per_sqm' | 'fixed',
    area_sqm: '',
    rate_per_sqm: '',
    fixed_rate: '',
    tenant_name: '',
    tenant_email: '',
    tenant_phone: '',
  });

  useEffect(() => {
    fetchProperties();
  }, []);

  const fetchProperties = async () => {
    try {
      const response = await propertyAPI.getAll();
      setProperties(response.data);
    } catch (error) {
      toast.error('Failed to load properties');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const data: any = {
      name: formData.name,
      address: formData.address,
      calculation_type: formData.calculation_type,
      tenant_name: formData.tenant_name || undefined,
      tenant_email: formData.tenant_email || undefined,
      tenant_phone: formData.tenant_phone || undefined,
    };

    if (formData.calculation_type === 'per_sqm') {
      data.area_sqm = parseFloat(formData.area_sqm);
      data.rate_per_sqm = parseFloat(formData.rate_per_sqm);
    } else {
      data.fixed_rate = parseFloat(formData.fixed_rate);
    }

    try {
      if (editingProperty) {
        await propertyAPI.update(editingProperty._id, data);
        toast.success('Property updated successfully');
      } else {
        await propertyAPI.create(data);
        toast.success('Property created successfully');
      }
      setShowModal(false);
      resetForm();
      fetchProperties();
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Operation failed');
    }
  };

  const handleEdit = (property: Property) => {
    setEditingProperty(property);
    setFormData({
      name: property.name,
      address: property.address,
      calculation_type: property.calculation_type,
      area_sqm: property.area_sqm?.toString() || '',
      rate_per_sqm: property.rate_per_sqm?.toString() || '',
      fixed_rate: property.fixed_rate?.toString() || '',
      tenant_name: property.tenant_name || '',
      tenant_email: property.tenant_email || '',
      tenant_phone: property.tenant_phone || '',
    });
    setShowModal(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this property?')) return;

    try {
      await propertyAPI.delete(id);
      toast.success('Property deleted successfully');
      fetchProperties();
    } catch (error) {
      toast.error('Failed to delete property');
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      address: '',
      calculation_type: 'per_sqm',
      area_sqm: '',
      rate_per_sqm: '',
      fixed_rate: '',
      tenant_name: '',
      tenant_email: '',
      tenant_phone: '',
    });
    setEditingProperty(null);
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-gray-900">Properties</h1>
          <button
            onClick={() => {
              resetForm();
              setShowModal(true);
            }}
            className="btn btn-primary"
          >
            + Add Property
          </button>
        </div>

        {loading ? (
          <div className="text-center py-12">Loading...</div>
        ) : properties.length === 0 ? (
          <div className="card text-center py-12">
            <p className="text-gray-500 mb-4">No properties found</p>
            <button onClick={() => setShowModal(true)} className="btn btn-primary">
              Create your first property
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {properties.map((property) => (
              <div key={property._id} className="card hover:shadow-lg transition-shadow">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-xl font-bold text-gray-900 mb-1">{property.name}</h3>
                    <p className="text-gray-600 text-sm">{property.address}</p>
                  </div>
                  <span className="badge badge-info">
                    {property.calculation_type === 'per_sqm' ? 'Per m²' : 'Fixed'}
                  </span>
                </div>

                <div className="space-y-2 mb-4">
                  {property.calculation_type === 'per_sqm' ? (
                    <>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-600">Area:</span>
                        <span className="font-medium">{property.area_sqm} m²</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-600">Rate:</span>
                        <span className="font-medium">${property.rate_per_sqm}/m²</span>
                      </div>
                      <div className="flex justify-between text-sm border-t pt-2">
                        <span className="text-gray-600">Monthly:</span>
                        <span className="font-bold text-primary">
                          ${((property.area_sqm || 0) * (property.rate_per_sqm || 0)).toFixed(2)}
                        </span>
                      </div>
                    </>
                  ) : (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-600">Fixed Rate:</span>
                      <span className="font-bold text-primary">${property.fixed_rate}</span>
                    </div>
                  )}
                </div>

                {property.tenant_name && (
                  <div className="border-t pt-4 mb-4">
                    <p className="text-sm text-gray-600 mb-1">Tenant</p>
                    <p className="font-medium">{property.tenant_name}</p>
                    {property.tenant_email && (
                      <p className="text-sm text-gray-500">{property.tenant_email}</p>
                    )}
                  </div>
                )}

                <div className="flex gap-2">
                  <button
                    onClick={() => handleEdit(property)}
                    className="btn btn-secondary flex-1"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(property._id)}
                    className="btn btn-danger flex-1"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-xl p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
              <h2 className="text-2xl font-bold mb-6">
                {editingProperty ? 'Edit Property' : 'Add New Property'}
              </h2>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="col-span-2">
                    <label className="label">Property Name</label>
                    <input
                      type="text"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="input"
                      required
                    />
                  </div>

                  <div className="col-span-2">
                    <label className="label">Address</label>
                    <input
                      type="text"
                      value={formData.address}
                      onChange={(e) => setFormData({ ...formData, address: e.target.value })}
                      className="input"
                      required
                    />
                  </div>

                  <div className="col-span-2">
                    <label className="label">Calculation Type</label>
                    <select
                      value={formData.calculation_type}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          calculation_type: e.target.value as 'per_sqm' | 'fixed',
                        })
                      }
                      className="input"
                    >
                      <option value="per_sqm">Per Square Meter</option>
                      <option value="fixed">Fixed Rate</option>
                    </select>
                  </div>

                  {formData.calculation_type === 'per_sqm' ? (
                    <>
                      <div>
                        <label className="label">Area (m²)</label>
                        <input
                          type="number"
                          step="0.01"
                          value={formData.area_sqm}
                          onChange={(e) => setFormData({ ...formData, area_sqm: e.target.value })}
                          className="input"
                          required
                        />
                      </div>
                      <div>
                        <label className="label">Rate per m²</label>
                        <input
                          type="number"
                          step="0.01"
                          value={formData.rate_per_sqm}
                          onChange={(e) =>
                            setFormData({ ...formData, rate_per_sqm: e.target.value })
                          }
                          className="input"
                          required
                        />
                      </div>
                    </>
                  ) : (
                    <div className="col-span-2">
                      <label className="label">Fixed Rate</label>
                      <input
                        type="number"
                        step="0.01"
                        value={formData.fixed_rate}
                        onChange={(e) => setFormData({ ...formData, fixed_rate: e.target.value })}
                        className="input"
                        required
                      />
                    </div>
                  )}

                  <div className="col-span-2 border-t pt-4">
                    <h3 className="font-medium mb-3">Tenant Information (Optional)</h3>
                  </div>

                  <div className="col-span-2">
                    <label className="label">Tenant Name</label>
                    <input
                      type="text"
                      value={formData.tenant_name}
                      onChange={(e) => setFormData({ ...formData, tenant_name: e.target.value })}
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="label">Tenant Email</label>
                    <input
                      type="email"
                      value={formData.tenant_email}
                      onChange={(e) => setFormData({ ...formData, tenant_email: e.target.value })}
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="label">Tenant Phone</label>
                    <input
                      type="tel"
                      value={formData.tenant_phone}
                      onChange={(e) => setFormData({ ...formData, tenant_phone: e.target.value })}
                      className="input"
                    />
                  </div>
                </div>

                <div className="flex gap-3 pt-4">
                  <button type="submit" className="btn btn-primary flex-1">
                    {editingProperty ? 'Update Property' : 'Create Property'}
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
