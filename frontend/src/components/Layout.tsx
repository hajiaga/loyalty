import { ReactNode, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';

interface LayoutProps {
  children: ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const router = useRouter();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const handleLogout = () => {
    localStorage.removeItem('token');
    router.push('/login');
  };

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: '📊' },
    { name: 'Properties', href: '/properties', icon: '🏢' },
    { name: 'Bills', href: '/bills', icon: '📄' },
    { name: 'Payments', href: '/payments', icon: '💳' },
    { name: 'Reports', href: '/reports', icon: '📈' },
  ];

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside
        className={`${
          sidebarOpen ? 'w-64' : 'w-20'
        } bg-primary text-white transition-all duration-300 flex flex-col`}
      >
        <div className="p-6 flex items-center justify-between">
          <h1 className={`text-xl font-bold ${!sidebarOpen && 'hidden'}`}>
            Property Billing
          </h1>
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="text-white hover:bg-primary-dark p-2 rounded"
          >
            {sidebarOpen ? '←' : '→'}
          </button>
        </div>

        <nav className="flex-1 px-4 space-y-2">
          {navigation.map((item) => (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                router.pathname === item.href
                  ? 'bg-primary-dark'
                  : 'hover:bg-primary-dark/50'
              }`}
            >
              <span className="text-2xl">{item.icon}</span>
              {sidebarOpen && <span className="font-medium">{item.name}</span>}
            </Link>
          ))}
        </nav>

        <div className="p-4 border-t border-primary-dark">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-primary-dark/50 transition-colors"
          >
            <span className="text-2xl">🚪</span>
            {sidebarOpen && <span className="font-medium">Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="bg-white shadow-sm border-b border-gray-200">
          <div className="px-8 py-4 flex items-center justify-between">
            <h2 className="text-2xl font-semibold text-gray-800">
              {navigation.find((item) => item.href === router.pathname)?.name || 'Dashboard'}
            </h2>
            <div className="flex items-center gap-4">
              <span className="text-gray-600">Welcome back!</span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-8 overflow-auto bg-gray-50">
          {children}
        </main>
      </div>
    </div>
  );
}
