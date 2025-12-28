-- Sample data for demonstrating Broken Access Control vulnerabilities

INSERT INTO users (id, username, email, password, role, phone_number, address, salary, ssn) VALUES
(1, 'john_doe', 'john@example.com', 'password123', 'USER', '555-0101', '123 Main St, Anytown, USA', 50000.00, '123-45-6789'),
(2, 'jane_smith', 'jane@example.com', 'password456', 'USER', '555-0102', '456 Oak Ave, Somewhere, USA', 60000.00, '987-65-4321'),
(3, 'bob_admin', 'bob@example.com', 'admin123', 'ADMIN', '555-0103', '789 Admin Blvd, Adminville, USA', 100000.00, '456-78-9012'),
(4, 'alice_user', 'alice@example.com', 'alicepass', 'USER', '555-0104', '321 User Lane, Usertown, USA', 55000.00, '234-56-7890'),
(5, 'charlie_manager', 'charlie@example.com', 'manager123', 'USER', '555-0105', '654 Manager Dr, Manageville, USA', 75000.00, '345-67-8901');
