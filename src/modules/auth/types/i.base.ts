export interface IResponse {
  code: number;
  success: boolean;
  message: string;
  error?: IError[];
  data?: any;
}
export interface IError {
  field: string;
  message: string;
}
export interface UserSecretJWT {
  userId: string;
  email: string;
  role: string;
  tokenVersion?: number;
}
