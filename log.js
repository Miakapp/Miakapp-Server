module.exports.debug = (process.env.DEBUG === 'true') ? console.log : () => {};
module.exports.log = (...data) => console.log(`[${new Date().toLocaleString()}]`, ...data);
