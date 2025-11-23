
export type Role = 'ADMIN' | 'STAFF' | 'ORGANISATION';
export type Lang = 'en' | 'fr' | 'ar';

export interface User {
  id: string;
  username: string;
  name: string;
  role: Role;
  isActive: boolean;
  password?: string; // In a real app, this is hashed
  updatedAt?: string;
}

export interface TeamStatus {
  id: string;
  userId: string;
  festivalDate: string;
  statusText: string;
  updatedAt: string;
}

export interface InstitutionGroup {
  id: string;
  institutionName: string;
  responsibleName: string;
  studentsCount: number;
  participationType: 'FILM' | 'CONVERSATION' | 'BOTH';
  morningLocation: string;
  afternoonLocation: string;
  firstReceiverId: string;
  guideId: string;
  festivalDate: string;
  createdBy: string;
  createdAt: string;
}

export interface Invitation {
  id: string;
  name: string;
  phone: string;
  invitationsCount: number;
  invitationType: 'Balcon' | 'Mezzanine';
  status: 'PENDING' | 'SENT' | 'FAILED';
  festivalDate: string;
  assignedTo: string; // User ID of the member responsible for this invitation
  sentBy?: string;
  sentAt?: string;
}

export interface Badge {
  id: string;
  type: string;
  holderName: string;
  fileName: string;
  fileData: string; // Base64 for demo purposes
  festivalDate?: string;
  createdBy: string;
  createdAt: string;
}

export interface Contact {
  id: string;
  name: string;
  role: string;
  phone: string;
  category: string;
  notes?: string;
  createdBy: string;
}

export interface Note {
  id: string;
  festivalDate: string;
  authorId: string;
  title: string;
  content: string;
  createdAt: string;
}

export interface Reminder {
  id: string;
  festivalDate: string;
  title: string;
  time: string;
  details?: string;
  createdBy: string;
  createdAt: string;
}

export interface DriveFile {
  id: string;
  uploaderId: string;
  fileName: string;
  fileData: string; // Base64
  fileType: string;
  size: number;
  visibility: 'PUBLIC' | 'PRIVATE';
  targetUserId?: string; // If PRIVATE
  description?: string;
  createdAt: string;
}

export interface LogEntry {
  id: string;
  userId: string;
  actionType: string;
  target: string;
  festivalDate?: string;
  timestamp: string;
}

export interface AppState {
  currentUser: User | null;
  currentDate: string;
  language: Lang;
}