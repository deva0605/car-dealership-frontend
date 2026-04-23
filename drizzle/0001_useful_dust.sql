CREATE TABLE `bookings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vehicleId` int NOT NULL,
	`customerName` text NOT NULL,
	`customerContact` varchar(255) NOT NULL,
	`customerId` varchar(255) NOT NULL,
	`transactionType` enum('sale','rental','service') NOT NULL,
	`amount` int NOT NULL,
	`rentalStartDate` timestamp,
	`rentalEndDate` timestamp,
	`notes` text,
	`status` enum('pending','confirmed','completed','cancelled') NOT NULL DEFAULT 'pending',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `bookings_id` PRIMARY KEY(`id`)
);
