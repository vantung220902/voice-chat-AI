import User from 'src/modules/user/entities/User.entity';
import {
  BaseEntity,
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
} from 'typeorm';

@Entity()
export class Message extends BaseEntity {
  @Column('uuid', {
    primary: true,
    name: 'message_id',
    default: () => 'uuid_generate_v4()',
  })
  messageId: string;

  @Column('character varying')
  content: string;

  @Column('character varying', { name: 'message_user_id' })
  userId: string;

  @ManyToOne(() => User, (user) => user.messages)
  @JoinColumn({ name: 'message_user_id', referencedColumnName: 'userId' })
  user: User;

  @CreateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  created_at: Date;
}
