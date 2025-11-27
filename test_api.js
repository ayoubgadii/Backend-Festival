import fetch from 'node-fetch';

const API_URL = 'http://localhost:3000/api';
// Replace with a valid token from your running application's localStorage or logs
const TOKEN = 'YOUR_VALID_JWT_TOKEN_HERE';

async function testUpdateGroup() {
    console.log('\n--- Testing Update Group ---');
    // You might need to replace this ID with a valid Group ID from your database
    const groupId = 'EXISTING_GROUP_ID_HERE';

    const payload = {
        institutionName: 'Updated Institution',
        responsibleName: 'Updated Responsible',
        studentsCount: 50,
        participationType: 'Full',
        festivalDate: '2023-10-27'
    };

    try {
        const res = await fetch(`${API_URL}/groups/${groupId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${TOKEN}`
            },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            console.log('✅ Group updated successfully');
        } else {
            const error = await res.json();
            console.log('❌ Group update failed:', res.status, error);
        }
    } catch (err) {
        console.error('❌ Network error:', err.message);
    }
}

async function testUpdateInvitation() {
    console.log('\n--- Testing Update Invitation ---');
    // Replace with a valid Invitation ID
    const inviteId = 'EXISTING_INVITATION_ID_HERE';

    const payload = {
        name: 'Updated Name',
        phone: '123456789',
        invitationsCount: 2,
        invitationType: 'VIP'
    };

    try {
        const res = await fetch(`${API_URL}/invitations/${inviteId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${TOKEN}`
            },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            console.log('✅ Invitation updated successfully');
        } else {
            const error = await res.json();
            console.log('❌ Invitation update failed:', res.status, error);
        }
    } catch (err) {
        console.error('❌ Network error:', err.message);
    }
}

async function testSendInvitation() {
    console.log('\n--- Testing Send Invitation (Status Update) ---');
    // Replace with a valid Invitation ID
    const inviteId = 'EXISTING_INVITATION_ID_HERE';

    const payload = {
        status: 'SENT',
        sentBy: 'Test Script'
    };

    try {
        const res = await fetch(`${API_URL}/invitations/${inviteId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${TOKEN}`
            },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            console.log('✅ Invitation status updated successfully');
        } else {
            const error = await res.json();
            console.log('❌ Invitation status update failed:', res.status, error);
        }
    } catch (err) {
        console.error('❌ Network error:', err.message);
    }
}

console.log('⚠️  NOTE: You need to update TOKEN and IDs in this script before running.');
// Uncomment to run tests
// testUpdateGroup();
// testUpdateInvitation();
// testSendInvitation();
