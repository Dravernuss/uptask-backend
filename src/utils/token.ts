export const generateToken = () =>
  Math.floor(10000 + Math.random() * 900000).toString();
