const usersDB = { '1001': { id: '1001', name: 'Alice', role: 'customer', balance: 50.0 } };

exports.updateUser = (id, payload) => {
    const user = usersDB[id];
    if (!user) return null;
    
    Object.keys(payload).forEach(key => {
        if (key !== 'id') user[key] = payload[key];
    });
    return user;
};