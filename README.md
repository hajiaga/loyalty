# Property Billing SaaS Application

A comprehensive SaaS application for property developers to manage utility billing, invoicing, and online payments through Stripe integration.

## Features

### Property Management
- Create and manage properties with two calculation types:
  - **Per Square Meter**: Calculate bills based on area (m²) × rate
  - **Fixed Rate**: Set a fixed monthly amount
- Store tenant information (name, email, phone)
- Track property details and addresses

### Billing System
- Automatic bill calculation based on property settings
- Create bills with customizable billing periods and due dates
- Track bill status (Pending, Paid, Overdue, Cancelled)
- Filter bills by status and property
- Manual status updates

### Payment Processing
- Stripe integration for online payments
- Multiple payment methods support (Stripe, Cash, Bank Transfer)
- Payment history tracking
- Automatic bill status updates on payment

### Reports & Analytics
- Dashboard with key metrics:
  - Total properties, bills, and payments
  - Revenue collected vs outstanding
  - Overdue bills tracking
- Property performance reports
- Payment history with date filtering
- Collection rate calculations
- Financial summaries

### Design
- QuickBooks/FreshBooks inspired interface
- Color scheme: Primary Blue (#2C5282), Success Green (#38A169), Danger Red (#E53E3E)
- Inter/Roboto font families
- Responsive design with sidebar navigation
- Card-based layouts and data tables

## Technology Stack

### Backend
- **FastAPI**: Modern Python web framework
- **MongoDB**: NoSQL database with Motor async driver
- **Stripe**: Payment processing integration
- **JWT**: Authentication and authorization
- **Pydantic**: Data validation

### Frontend
- **Next.js 14**: React framework with SSR
- **TypeScript**: Type-safe JavaScript
- **Tailwind CSS**: Utility-first CSS framework
- **Axios**: HTTP client
- **React Hot Toast**: Notifications
- **date-fns**: Date formatting

## Installation

### Prerequisites
- Python 3.10+
- Node.js 18+
- MongoDB 5.0+
- Stripe account (for payment processing)

### Backend Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd loyalty
```

2. Create and activate virtual environment:
```bash
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Start MongoDB (if not already running):
```bash
# macOS with Homebrew
brew services start mongodb-community

# Linux
sudo systemctl start mongod

# Windows
net start MongoDB
```

6. Run the backend server:
```bash
python main.py
# Or with uvicorn directly:
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`
API documentation: `http://localhost:8000/docs`

### Frontend Setup

1. Navigate to frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment variables:
```bash
cp .env.local.example .env.local
# Edit .env.local with your configuration
```

4. Run the development server:
```bash
npm run dev
```

The application will be available at `http://localhost:3000`

## Environment Variables

### Backend (.env)
- `SECRET_KEY`: JWT secret key for authentication
- `MONGODB_URL`: MongoDB connection string
- `STRIPE_SECRET_KEY`: Stripe secret API key

### Frontend (frontend/.env.local)
- `NEXT_PUBLIC_API_URL`: Backend API URL (default: http://localhost:8000)
- `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`: Stripe publishable key

## API Endpoints

### Authentication
- `POST /register` - Register new merchant account
- `POST /token` - Login and get JWT token
- `GET /me` - Get current user information

### Properties
- `GET /properties` - List all properties
- `POST /properties` - Create new property
- `GET /properties/{id}` - Get property details
- `PUT /properties/{id}` - Update property
- `DELETE /properties/{id}` - Delete property

### Bills
- `GET /bills` - List all bills (with filters)
- `POST /bills` - Create new bill (auto-calculates amount)
- `GET /bills/{id}` - Get bill details
- `PUT /bills/{id}` - Update bill
- `DELETE /bills/{id}` - Delete bill

### Payments
- `GET /payments` - List all payments
- `POST /payments/create-payment-intent` - Create Stripe payment intent
- `POST /payments/confirm` - Confirm payment and update bill

### Reports
- `GET /reports/summary` - Get dashboard summary
- `GET /reports/properties` - Get property reports
- `GET /reports/payment-history` - Get payment history

## Usage Guide

### Creating Your First Property

1. Navigate to **Properties** page
2. Click **Add Property** button
3. Fill in property details:
   - Name and address
   - Choose calculation type (Per m² or Fixed)
   - Enter rates or area
   - Add tenant information (optional)
4. Click **Create Property**

### Generating Bills

1. Navigate to **Bills** page
2. Click **Create Bill** button
3. Select a property
4. Set billing period dates
5. Set due date
6. Amount is calculated automatically based on property settings
7. Click **Create Bill**

### Processing Payments

1. Navigate to **Bills** page
2. Find a pending bill
3. Click **Mark Paid** to manually mark as paid
4. Or use Stripe integration for online payments
5. View payment history in **Payments** page

### Viewing Reports

1. Navigate to **Reports** page
2. View overall statistics and metrics
3. Check property performance table
4. Analyze collection rates and outstanding amounts

## Stripe Integration

To enable online payments:

1. Create a Stripe account at https://stripe.com
2. Get your API keys from Stripe Dashboard
3. Add keys to environment variables:
   - Backend: `STRIPE_SECRET_KEY`
   - Frontend: `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`
4. Use the payment intent API to process payments

## Database Schema

### Collections

**merchants**
- name, email, password (hashed)
- created_at

**properties**
- merchant_id, name, address
- calculation_type, area_sqm, rate_per_sqm, fixed_rate
- tenant_name, tenant_email, tenant_phone
- created_at, updated_at

**bills**
- merchant_id, property_id
- amount, status
- billing_period_start, billing_period_end, due_date
- description, created_at, updated_at

**payments**
- merchant_id, property_id, bill_id
- amount, payment_method, status
- stripe_payment_intent_id
- paid_at, created_at

## Development

### Running Tests
```bash
# Backend
pytest

# Frontend
cd frontend
npm test
```

### Building for Production

Backend:
```bash
# Use a production WSGI server
pip install gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker
```

Frontend:
```bash
cd frontend
npm run build
npm start
```

## Security Notes

- Change `SECRET_KEY` in production
- Use environment variables for sensitive data
- Enable HTTPS in production
- Configure CORS properly for your domain
- Keep dependencies updated
- Use strong passwords for MongoDB
- Restrict MongoDB access to localhost in production

## License

MIT License

## Support

For issues and questions, please create an issue in the repository.
