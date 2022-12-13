const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../../models/user');

module.exports = {
    createUser: async args => {
        try {
            const checkUser = await User.findOne({email: args.userInput.email})
            if (checkUser) {
                throw new Error('User exists already.')
            }
            const hashedPassword = await bcrypt.hash(args.userInput.password, 12);
            const user = new User({
                email: args.userInput.email,
                password: hashedPassword
            });
            const result = await user.save();
            return {
                ...result._doc, 
                password: null, 
                _id: result.id
            }
        }
        catch (err) {
            console.log(err);
            throw err;
        }
    },
    login: async ({email, password}) => {
        const user = await User.findOne({email: email});
        if (!user) {
            throw new Error ('Invalid credentials')
        }
        const isEqual = await bcrypt.compare(password, user.password);
        if (!isEqual) {
            throw new Error ('Invalid credentials')
        }
        const token = jwt.sign({userId: user.id, email: user.email}, 'HSA78GF45', {
            expiresIn: '1h'
        });
        return { userId: user.id, token: token, tokenExpiration: 1}
    }
};